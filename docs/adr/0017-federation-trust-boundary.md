<!-- Source: docs/tasks/phase-2/2.1-adr-federation-trust-boundary.md, forced by Feature 06 (T06). -->
> **Nav:** [ADR index](./README.md) · [ADR 0002 (federation mechanism)](./0002-federation-mechanism.md) ·
> [ADR 0001 (identity scheme)](./0001-identity-scheme.md) ·
> [ADR 0016 (envelope deniability)](./0016-envelope-deniability.md) ·
> [wire protocol](../api/wire-protocol.md) · [rendezvous protocol v1](../api/rendezvous-protocol-v1.md) ·
> [system design §3.3](../architecture/system-design.md) · [threat model](../security/threat-model.md)

# ADR 0017: Federation trust boundary — peer authentication and cross-org `from` attestation

**Status:** Accepted. **Extends** [ADR 0002](./0002-federation-mechanism.md) (server-to-server
signaling over mTLS). **Scope-corrects** [ADR 0016](./0016-envelope-deniability.md) residual R4 (see
[Consequences](#consequences)). Supersedes nothing.

## Context

Feature 06 turns the single-hop route `client → own server → client` into a two-hop, cross-trust-
boundary route `client → own server (A) → foreign server (B) → client`. Three questions have to be
answered before any s2s byte is shaped, and none of them may be left as `TODO: confirm`:

**(a) Peer-certificate identity.** mTLS authenticates the *transport* between A and B. What must the
peer certificate say for that authentication to mean anything? [System design §3.3](../architecture/system-design.md#33-cross-server-rendezvous-with-no-central-directory)
already states mTLS "contributes nothing to end-to-end security" — but it does gate *routing and
anti-abuse* decisions (which server is B, what policy/rate-limit bucket applies), so getting it wrong
is not harmless. In **private-CA / air-gap mode this is the whole trust model**: if the peer cert is
only checked against "signed by our shared federation CA," then *any* org enrolled under that CA —
not just the intended partner — can present a valid cert and be accepted as any other org, because a
private CA has no CA/Browser-Forum-style external domain-validation discipline behind it. The two-org
air-gap demo is explicitly the primary target deployment ([ADR 0002](./0002-federation-mechanism.md)),
so this is not an edge case.

**(b) Cross-org `from` attestation — the forcing problem.** `Deliver{from, blob}`
([rendezvous-protocol-v1 §1](../api/rendezvous-protocol-v1.md)) is required by the client:
`apps/core/src/chat.rs::open_bytes` hard-rejects `envelope.sender_pub != from` with
`ChatError::SenderMismatch`. But [wire-protocol.md §4](../api/wire-protocol.md#4-server--server-federation-mtls)'s
`fed_route{to, envelope}` carries **no** `from`, and server A cannot derive one: the envelope is opaque
routing payload (`tools/lint-no-serde-on-blob.sh`), and decoding it to read `sender_pub` would require
`meridian-envelope`, which the server must never depend on
([lint-server-no-core.sh](../../tools/lint-server-no-core.sh)). As specified, **the federated forwarding
path is not implementable.** A third, independently divergent shape exists —
[wire-protocol.md §2](../api/wire-protocol.md#2-client--rendezvous-wss) lists `deliver{from_server,
blob}`, a different field name from the implemented `Deliver{from}` — which this ADR does not need to
resolve itself (that reconciliation belongs to [2.2](../tasks/phase-2/2.2-federation-protocol-v1.md)/
[2.3](../tasks/phase-2/2.3-c2s-federation-extension.md)) but does need to *name the canonical answer*
for those tasks to implement.

**(c) Origin identity for federation-edge rate limits.** [wire-protocol.md §4](../api/wire-protocol.md#4-server--server-federation-mtls)
already says rate limits are "keyed by (origin server, origin account)." Both halves of that key need a
concrete source now that "origin" can mean a party server A never authenticated directly.

## (a) Peer-certificate identity

**Options.**
- **A. Trust any cert issued by a trusted root** (public WebPKI root store, or "signed by our shared
  private CA"), with no binding to a specific expected identity. Simplest; **rejected** — this is
  exactly the private-CA impersonation hole above, and even in WebPKI mode it would accept a cert for
  *any* domain the root store trusts, not the domain A actually intended to dial.
- **B. Pin verification to the domain A intended to reach — the hint/discovery domain, never the
  literal SRV target hostname — in both WebPKI and private-CA modes; the static map records the
  expected identity explicitly per entry. (Chosen.)**
- **C. Pin to the certificate's SPKI fingerprint** (key/cert pinning) instead of, or in addition to, a
  name. Strongest against CA compromise or mis-issuance, but couples cert rotation to an out-of-band
  pin update on every federation partner — an operational burden with no test harness to exercise it
  in v1. **Rejected as the v1 default**; not precluded as a later per-partner hardening option (see
  Consequences) since it composes with B rather than replacing it.
- **D. mTLS plus an application-layer challenge-response** (mirroring the client's `Auth` handshake) to
  re-prove server identity above TLS. **Rejected** — mTLS already produces an authenticated channel for
  the connection's lifetime; a second signature over the same key material A already validated during
  the handshake adds no capability the attacker doesn't already need to break (the server's private
  key), only more code to get wrong.

**Decision: B.**

1. **Verification target is the hint/discovery domain, not the SRV target host.** DNS SRV
   (`_meridian-fed._tcp.<domain>`) is a *discovery* mechanism only — it says where to dial, never who
   to trust ([ADR 0001](./0001-identity-scheme.md) consequences: "hint staleness is a real failure
   mode," not a security boundary). The SRV response itself is unauthenticated DNS. If certificate
   validation were performed against the literal SRV target hostname, a spoofed or hijacked SRV record
   could redirect *which name gets checked*, not just where the TCP connection lands. Binding
   validation to the domain A actually intended to reach — the domain from the ID's `@hint` /
   `federation_map.toml` key — means a hijacked SRV record only redirects the TCP dial; TLS validation
   still fails closed unless the attacker also holds a cert for the real target domain. This is the
   same "authenticate the origin you meant, not the record that pointed you there" pattern used by
   XMPP/Matrix server-to-server dialback.
2. **WebPKI mode:** standard hostname verification against the OS/system trust root — the peer cert's
   SAN must include the hint domain.
3. **Private-CA mode:** trusting "signed by the shared federation CA" is not sufficient on its own (the
   impersonation hole above). Each `federation_map.toml` entry **must** carry an explicit pinned peer
   identity (SAN/CN) for that specific partner, decided at operator configuration time — "pinning a
   partner" *is* writing that entry. A connection succeeds only if the peer cert **both** chains to the
   configured private CA **and** presents the identity pinned for that map entry specifically. A cert
   that merely chains to the trusted CA, for a different org's name, is rejected — the CA is a
   necessary trust anchor but never a sufficient one.
4. This gives WebPKI and private-CA modes **one verification rule** (chain to a trusted root; SAN
   matches the domain A meant to reach), differing only in what the trusted root and the "domain A
   meant to reach" are configured from (system store + hint vs. private CA + static-map pin).

## (b) Cross-org `from` attestation

**Options.**
- **A. `fed_route` carries no `from`; server A infers it some other way.** **Rejected** — this is the
  forcing problem above; there is no other way that doesn't decode the opaque envelope.
- **B. `fed_route` gains an explicit `from: bstr[32]` field, asserted by the origin server (B), carried
  as routing metadata alongside — never decoded from — the opaque envelope blob; A relays it verbatim
  as the `from` in the `Deliver{from, blob}` it pushes to its own client, exactly as it already does for
  a purely local route. (Chosen.)**
- **C. A cryptographic s2s provenance attestation** — B signs `(to, envelope_hash, from)` under its own
  server key, checkable by A. **Rejected for v1**: the channel it would ride (the mTLS session between
  A and B) is already authenticated at the transport layer per (a); forging such an attestation
  requires the same key compromise as forging the mTLS session itself, so it adds verification code
  without adding a capability an attacker doesn't already need. The property that actually matters —
  whether the claimed sender can be trusted — is not strengthened by a server-level signature at all
  (see below); it comes from the client-side envelope check, which this option does not touch. Revisit
  only if federation routing ever becomes multi-hop (today it is exactly two hops, A↔B, per
  [ADR 0002](./0002-federation-mechanism.md) and [system design §3.3](../architecture/system-design.md);
  `TODO: confirm` if that scope ever changes).
- **D. Require the `from` account to be cryptographically bound to B's own domain** (e.g., A checks that
  `from`'s ID hint resolves to B). **Rejected** — hints are advisory, never an identity authority
  ([ADR 0001](./0001-identity-scheme.md)); an ID's hint can be stale or absent this check without being
  an attack (the stale-hint case in the [feature spec](../architecture/features/06-cross-org-federation.md)
  is explicitly *not* a security case). Enforcing hint-to-server binding would turn an advisory field
  into a load-bearing one and break the documented stale-hint UX.

**Decision: B.** `fed_route` carries `from` as a field alongside `to` and `envelope`, asserted by the
sending server. This is **not** a new trust primitive: it is the exact same "server testimony" category
[ADR 0016 residual R4](./0016-envelope-deniability.md) already accepts for the single-hop case — an
operator attesting that a blob arrived on a given account's authenticated connection — pushed one hop
further along a path A already chose to trust when it decided to federate with B (subject to (a) and
the policy in [2.6](../tasks/phase-2/2.6-federation-policy-limits.md)). The reason this is safe to
accept rather than a new attack surface:

- **The client-side check does not weaken.** Alice's client still rejects any envelope where
  `sender_pub != from` (`ChatError::SenderMismatch`), now comparing against the `from` B asserted and A
  relayed. B lying about `from` for an envelope it forwards produces a mismatch, not a successful
  impersonation.
- **B cannot forge authorship it doesn't hold.** Under envelope v1, `sender_pub` is bound by an
  Ed25519 signature B cannot produce without the corresponding private key. Under v2
  ([ADR 0016](./0016-envelope-deniability.md)), it is bound by the ratchet AEAD to the identity keys in
  `AD`. Either way, a malicious B can only truthfully forward envelopes actually signed/encrypted by
  keys it controls — which, in practice, bounds it to **misattributing among its own accounts**, the
  same capability a malicious *local* server already has over its own users. Federation does not grant
  B a new capability against identities it does not hold; it extends B's existing one-hop reach to A's
  client instead of stopping at B's own.
- **This is bilateral trust, already the accepted model.** [ADR 0002](./0002-federation-mechanism.md):
  "federation abuse handled bilaterally (rate limits, allowlists) rather than by global consensus." A
  never has to trust an account it didn't choose to federate toward — it trusts B, per (a) and per its
  own federation policy, to correctly identify its own users. That is the whole bilateral bet
  federation makes, stated once, not a new one made per-message.

## (c) Origin identity for federation-edge rate limits

**Options.**
- **A. Key rate limits only by origin server.** Simpler, but one hostile or compromised account on an
  otherwise-honest large partner org can exhaust the shared per-server budget for every other user on
  that org. **Rejected** as the sole key — too coarse given wire-protocol.md §4 already specifies a
  finer key.
- **B. Origin server = the mTLS peer identity established under (a); origin account = the `from`
  server B asserts under (b). (Chosen.)** Matches wire-protocol.md §4's existing "(origin server,
  origin account)" key exactly.
- **C. Require per-account rate-limit tokens signed by the account itself**, not server-asserted.
  **Rejected for v1** as unneeded cryptographic machinery: the per-server axis (B) is the actual
  backstop, cryptographically grounded in mTLS, and a malicious server relabeling its own traffic
  across fabricated account labels only *redistributes* load within its own per-server budget — it
  cannot exceed it. Account-level fairness beyond that is a quality-of-service concern, not a security
  one.

**Decision: B.** "Origin server" is grounded in the mTLS peer identity from (a) — cryptographic, cannot
be spoofed without breaking (a). "Origin account" is grounded in the `from` testimony from (b) — server
attestation, not independently verifiable by A, and **must be documented as such**: it is sufficient for
fairness/abuse shaping (a malicious B redistributing its own budget across fake `from` labels is a
quality-of-service problem, bounded by the per-server ceiling) but must never be treated as an identity
guarantee for anything beyond rate-limit bucketing.

## Binding conditions

These are normative for [2.2](../tasks/phase-2/2.2-federation-protocol-v1.md)/
[2.3](../tasks/phase-2/2.3-c2s-federation-extension.md) onward; Feature 06 must not ship without them.

**C1 — `fed_route` MUST carry `from: bstr[32]`**, asserted by the sending server, alongside `to` and
`envelope`. It is routing metadata carried next to the opaque blob, never decoded from it — this does
not create a server-no-core or opacity-lint violation.

**C2 — Canonical shape.** Of the three divergent forms in context (b), the canonical s2s shape is
`fed_route{to, from, envelope}` (this ADR's addition to wire-protocol.md §4's existing definition); the
canonical c2s push to the client remains `Deliver{from, blob}` (rendezvous-protocol-v1 §1, unchanged —
it already has the field this ADR requires upstream of it). `wire-protocol.md §2`'s `deliver{from_server,
blob}` is a stale duplicate of the c2s `Deliver` op and must be reconciled to `Deliver{from, blob}`; the
actual doc edit is [2.2](../tasks/phase-2/2.2-federation-protocol-v1.md)/[2.3](../tasks/phase-2/2.3-c2s-federation-extension.md)'s,
not this ADR's, but the name to reconcile *to* is decided here.

**C3 — Certificate validation target is the hint/discovery domain, never the literal SRV/static-map
dial target**, in both WebPKI and private-CA modes (see (a)).

**C4 — `federation_map.toml` entries MUST carry an explicit pinned peer identity** (SAN/CN) per partner;
a private-CA cert that chains to the trusted CA but does not match the entry's pinned identity MUST be
rejected. This is a schema requirement handed to
[2.5](../tasks/phase-2/2.5-federation-discovery.md).

**C5 — Rate limiting keys "origin server" to the mTLS peer identity from (a) and "origin account" to the
`from` from (b)**, per (c); per-server limits are the enforced backstop and must not be bypassable by
account-label churn. Handed to [2.6](../tasks/phase-2/2.6-federation-policy-limits.md).

**C6 — [ADR 0016](./0016-envelope-deniability.md) residual R4 is scope-corrected** to state its "routing
`from` is taken from the authenticated WebSocket session" claim is true only single-hop, and point to
this ADR for the federated case (see [Consequences](#consequences)).

## Accepted residual risks

> **R1 — Bilateral misattribution.** A malicious or compromised server B can mislabel which of its
> *own* accounts originated a given envelope it legitimately holds (it cannot forge one it does not
> control — see (b)). This is the A2 threat-model capability ("colludes with a malicious counterpart
> server in a federation") extended one hop, not a new capability. Mitigation is policy, not crypto:
> `allowlist`/`closed` federation modes ([2.6](../tasks/phase-2/2.6-federation-policy-limits.md)) let an
> org choose which servers it accepts this bilateral bet from at all.

> **R2 — Private-CA issuance error or compromise still impersonates within the pin.** Pinning (C4)
> stops a cert for the *wrong* org from being accepted even though it chains to the shared CA; it does
> not protect against the private CA itself mis-issuing or being compromised into signing a cert that
> matches a specific pinned identity. This is the direct analogue of public-CA compromise risk in
> WebPKI mode and is accepted on the same basis: the alternative (SPKI pinning, option C in (a)) trades
> this residual for an operational rotation burden with no v1 test harness, and is left as a documented
> future hardening rather than a v1 requirement.

> **R3 — No multi-hop attestation model.** This ADR's `from`-attestation answer is scoped to exactly
> two hops (A↔B), matching [ADR 0002](./0002-federation-mechanism.md)'s bilateral model and current
> system design. It does not define how attestation composes if federation routing is ever extended to
> transit through a third server. `TODO: confirm` if that ever becomes in-scope — it is explicitly out
> of this ADR's remit today.

> **R4 — Per-account rate-limit fairness is not a security guarantee.** As stated in (c), the "origin
> account" axis is server testimony; a malicious B can spread its own traffic across fabricated account
> labels to blunt per-account throttling. The per-server ceiling is the actual enforced bound.

## Consequences

- **[ADR 0016](./0016-envelope-deniability.md) residual R4 is edited** to read: "...the routing `from`
  is taken from the authenticated WebSocket session **for a single-hop route**. For a federated route,
  the routing `from` a client sees originates as the sending server's assertion, relayed unchanged by
  the receiving server — see [ADR 0017](./0017-federation-trust-boundary.md) — so federated server
  testimony is one hop further from the client than the single-hop case and requires trusting the
  federation partner an org's own server chose to route to, not only its own operator." This does not
  change R4's core point (server testimony is not a transferable cryptographic proof); it corrects the
  claim from single-hop-only to state the federated case explicitly instead of leaving it silently
  out of scope.
- **[ADRs 0001–0008](./README.md) flip from `Proposed` to `Accepted`.** This phase builds directly on
  [ADR 0002](./0002-federation-mechanism.md) (federation mechanism) and [ADR 0001](./0001-identity-scheme.md)
  (hint is advisory, used throughout (a) and (b) above); [CLAUDE.md](../../CLAUDE.md) and the ADR index
  already treat 0001–0008 as binding, and this ADR must not inherit a formally `Proposed` parent. Done
  as a status-line edit only — no ADR content changes; the options/trade-offs/decision text for each
  was already settled at design time and none of it is disturbed here.
- **[2.2](../tasks/phase-2/2.2-federation-protocol-v1.md)** writes `federation-protocol-v1.md` with
  `fed_route{to, from, envelope}` per C1/C2, and reconciles wire-protocol.md §2/§4's divergent shapes to
  the canonical `Deliver{from, blob}` naming.
- **[2.4](../tasks/phase-2/2.4-s2s-mtls-link.md)** implements domain-pinned certificate verification
  (C3) for both WebPKI and private-CA dialers/listeners — not "chains to a trusted root" alone.
- **[2.5](../tasks/phase-2/2.5-federation-discovery.md)** adds the pinned-identity field to
  `federation_map.toml`'s schema (C4).
  **[2.6](../tasks/phase-2/2.6-federation-policy-limits.md)** keys federation-edge rate limits per C5.
- No wire bytes are shaped by this ADR itself — it is docs/ADR only, per its task's Scope.
