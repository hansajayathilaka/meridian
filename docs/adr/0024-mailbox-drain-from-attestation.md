<!-- Source: docs/tasks/phase-8/8.7-mailbox-delivery-reconnect-ack.md, architect consult forced by the
     task's own implementation (found while building the delivery-on-reconnect drain). -->
> **Nav:** [ADR index](./README.md) · [ADR 0007 (offline mailbox)](./0007-offline-mailbox.md) ·
> [ADR 0016 (envelope deniability)](./0016-envelope-deniability.md) ·
> [ADR 0017 (federation trust boundary)](./0017-federation-trust-boundary.md) ·
> [data model](../architecture/data-model.md) ·
> [anonymity & retention](../security/anonymity-and-retention.md) ·
> [task 8.7](../tasks/phase-8/8.7-mailbox-delivery-reconnect-ack.md)

# ADR 0024: Mailbox-drain `Deliver.from` — no persisted sender identity, a fixed placeholder instead

**Status:** Accepted. **Scope-corrects** [ADR 0016](./0016-envelope-deniability.md) residual R4 for a
third case R4 didn't anticipate (see [Consequences](#consequences)). Supersedes nothing.

## Context

`Deliver{from, blob, mailbox_id}` ([wire-protocol.md §2](../api/wire-protocol.md#2-client--rendezvous-wss))
requires `from: bstr[32]` — a non-optional field, shipped in task 8.3. `apps/core/src/chat.rs::open_bytes`
hard-rejects `envelope.sender_pub != from` with `ChatError::SenderMismatch`, unchanged since v1.

For a **live** route (`ws::deliver_one`, task T03) and a **federated live** route (`fed_route`, ADR
0017), `from` is the routing server's own assertion — the connection-authenticated `account_pub` for
a same-server route, the `FedRoute.from` a sending org self-asserts for a federated one. ADR 0016's
residual R4 already names this precisely: server testimony an operator can attest to, "not a
transferable cryptographic proof" — weaker than the ratchet AEAD's own authentication, which is what
actually rejects a forged envelope.

Task 8.7 (delivery-on-reconnect) introduces a **third** case: a mailbox-drained push, where the
original sender's connection closed — possibly days ago, up to `config.mailbox.ttl_days`. The server
has no live assertion to make. The only way to populate `from` here is to have **persisted** the
sender's identity at enqueue time (tasks 8.5/8.6) alongside `recipient_pub` and the timestamp.

That is exactly what [data-model.md](../architecture/data-model.md)'s mailbox table explicitly rules
out ("Deliberately absent: ... sender columns on mailbox rows") and what
[anonymity-and-retention.md](../security/anonymity-and-retention.md)'s must-never list, item 2,
forbids outright: "Never store a server-side contact graph or materialize who-talks-to-whom beyond
transient routing." A `from_pub` column on a row that can persist for up to 14 days, readable via
`meridian-admin mailbox dump` ([8.11](../tasks/phase-8/8.11-meridian-admin-mailbox-dump.md)), is
precisely a durable, queryable `(sender, recipient, timestamp)` contact-graph edge — not transient.

The apparent way out: `MessageEnvelope::sender_pub` (`apps/envelope`) is **already** embedded in the
envelope's own wire structure, as authenticated outer plaintext (folded into the ratchet's X3DH-derived
AAD, not itself encrypted — v2 dropped the separate identity-key signature, per ADR 0016). A client
recovers it from `blob` directly, with no session state and no help from the server. `Deliver.from` was
never the crypto trust anchor for a live route either; `envelope.sender_pub` plus the ratchet AEAD is.

## Options

- **A. Persist sender identity server-side** (a `from_pub` column on the mailbox row), and keep
  `open_bytes`'s `SenderMismatch` check unchanged for a mailbox-drained push exactly as for a live one.
  **Rejected** — directly contradicts data-model.md's explicit mailbox-schema note and
  anonymity-and-retention.md's must-never #2. Not a close call: this is the literal shape of a
  server-side contact graph, and ADR 0007's own text points the opposite direction ("sender-signature
  *inside* the encryption where possible via sealed-sender-style wrapping").
- **B. Don't persist sender identity server-side. On drain, push `Deliver{from: <fixed placeholder>,
  blob, mailbox_id: Some(id)}`; client-side reception for a mailbox-tagged `Deliver` derives the real
  sender from `envelope.sender_pub` (already recoverable from `blob` alone) instead of requiring it to
  equal a routing-layer `from` the server cannot honestly provide. (Chosen.)**
- **C. Widen `Deliver.from` to `Option<[u8; 32]>`, omitted on a mailbox-drained push.** A real wire
  change (this field shipped non-optional in task 8.3), and functionally equivalent to B once the
  client-side handling exists — B keeps the wire shape byte-identical (no re-vectoring) and gives every
  consumer of `Deliver.from` a concrete, typed value rather than an `Option` most call sites would
  immediately need to special-case anyway. **Rejected** in favor of B for that reason; not reopened
  without a fresh forcing function.

## Decision

**Option B.** The mailbox never learns, stores, or serves who sent a queued envelope. A fixed sentinel
value — the all-zero key, `[0u8; 32]` — is emitted as `Deliver.from` on every mailbox-drained push, as
a named constant in `apps/proto` (never the recipient's own key: that could collide with a genuine
self-send and reads as a real claim rather than an obvious sentinel; `[0u8; 32]` cannot collide with
any ADR-0001 self-certifying account key, which is derived from real key material).

Client-side reception of a `Deliver` carrying `mailbox_id: Some(_)` must not require `from` to equal
`envelope.sender_pub` — the check exists to catch a live/federated routing server forging its own
testimony, and a mailbox-drained push carries no such testimony to forge. The real sender for a
mailbox-drained message comes from `envelope.sender_pub` alone, authenticated the same way it always
was: by the ratchet AEAD succeeding at all. This client-side change is **not** task 8.7's to build
(8.7's scope is `apps/rendezvous/src/ws.rs`'s connection handler only) — it is now folded into
[8.8](../tasks/phase-8/8.8-client-mailbox-ack-dedup.md)'s scope, which already touches
`apps/core/src/chat.rs` for the adjacent `eid`-dedup confirmation and already depends on 8.7 landing
first. Until 8.8 ships this, a mailbox-drained message deterministically hits `SenderMismatch`
client-side — a functionality gap, not a security one (fails closed, not open).

## Pros

- Zero server-side contact-graph exposure, for the life of every mailbox row — matches ADR 0007's own
  "as ciphertext-only as the transport allows" framing and the must-never list without exception.
- No wire-shape change: `Deliver.from` stays the exact type task 8.3 shipped, no vector regeneration.
- The actual authentication a client relies on (ratchet AEAD over AAD including `sender_pub`) is
  unchanged and unweakened — this ADR removes a defense-in-depth check for exactly the one case it
  cannot honestly evaluate, not the primary trust boundary itself.

## Cons (accepted, with mitigations)

- **A mailbox-drained message loses the "operator attests to relaying this" defense-in-depth layer**
  ADR 0016 R4 already scoped as weak (operator-trust testimony, not cryptographic proof) — for this
  case specifically, the operator has nothing honest to attest, so removing the check is more accurate
  than keeping a check that can never pass. Mitigation: none needed: the ratchet AEAD is the real
  boundary and is untouched.
- **A fixed sentinel is a slightly unusual API shape** (a "real-looking" field carrying a value that
  means "no assertion") compared to `Option`. Mitigation: named constant, documented at the `Deliver`
  type itself (`apps/proto/src/msg.rs`) and in this ADR, so it's discoverable rather than a magic value.
- **8.8 must land before mailbox-drained delivery is actually usable end to end** — 8.7 alone leaves a
  client-visible functionality gap (every drained message rejected). Mitigation: this is already true
  of the dependency order the phase-8 plan set (8.8 depends on 8.7); this ADR just names the specific
  fix 8.8 must include, rather than leaving it implicit.

## Consequences

- [data-model.md](../architecture/data-model.md)'s mailbox table note ("sender is inside the sealed
  envelope") gets a one-line precision edit: `sender_pub` is outer plaintext authenticated via AAD, not
  ciphertext — the existing line's intent (no sender column, ever) stands unchanged.
- [apps/proto/src/msg.rs](../../apps/proto/src/msg.rs)'s `Deliver` doc comment documents the mailbox-
  drain placeholder value and cites this ADR.
- [8.8](../tasks/phase-8/8.8-client-mailbox-ack-dedup.md)'s Scope gains the `SenderMismatch`
  restructuring for `mailbox_id.is_some()`, and its Deliverables/Tests reflect that the redelivery-
  dedup test (Deliverable 3) is unreachable without it — dedup is checked strictly after the sender
  check in `open_bytes` today.
- No change to ADR 0007 or ADR 0016 themselves (immutable once accepted) — this ADR narrows R4's scope
  the same way [ADR 0017](./0017-federation-trust-boundary.md) already did for the federated case.
