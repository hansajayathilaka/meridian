<!-- Source: T06 (feature 06-cross-org-federation), task 2.2. Server↔server framing, concretized. -->
> **Nav:** [docs index](../INDEX.md) · [api reference](./README.md) · [wire protocol](./wire-protocol.md) · [rendezvous protocol v1](./rendezvous-protocol-v1.md) · [ADR 0002](../adr/0002-federation-mechanism.md) · [ADR 0017](../adr/0017-federation-trust-boundary.md)

# Federation Protocol — v1 (server ↔ server)

Concrete framing for T06 cross-org federation, normative companion to
[wire-protocol.md §4](./wire-protocol.md#4-server--server-federation-mtls). It specifies exactly
what two federating `meridian-rendezvous` instances speak over their mTLS link. Encoding is
**deterministic CBOR** (RFC 8949) via `ciborium`; the shared types live in
[`meridian-proto`](../../apps/proto) (`apps/proto/src/fed.rs`) so no two implementations can
drift.

This doc is **contracts-only** (task 2.2): it fixes the wire shape and vectors every later task
codes against. It defines **no behavior** — the listener/dialer (2.4), discovery (2.5), policy and
rate limits (2.6), and the fetch/route/reachability handlers (2.7/2.8) are separate tasks.

## 0. Trust boundary (read [ADR 0017](../adr/0017-federation-trust-boundary.md) first)

Everything below implements ADR 0017's decisions verbatim; this doc does not re-derive them.
Three points matter most for reading the wire shapes:

- **The mTLS peer certificate, validated in-process, is the only authoritative identity** for any
  routing/policy/rate-limit decision (ADR 0017 (a)/C7). Certificate validation targets the
  hint/discovery domain, never the literal SRV/static-map dial target (C3).
- **`FedRoute` carries `from: bstr[32]`** as routing metadata asserted by the sending (origin)
  server, carried alongside — never decoded from — the opaque `envelope` (C1/C2). The receiving
  server relays it verbatim as the `from` in the `Deliver{from, blob}` it pushes to its own
  client, exactly as it already does for a purely local route.
- **Rate limits key "origin server" to the mTLS peer identity and "origin account" to the
  asserted `from`** (C5); the per-server axis is the enforced backstop, the per-account axis is
  server testimony, not an identity guarantee.

## 1. Transport & framing

After the mTLS handshake completes — cert validated **in-process**, never at a proxy/VIP upstream
of the server (ADR 0017 C7) — the connection carries a stream of length-delimited CBOR frames
**directly on the raw TLS byte stream**. There is no WebSocket upgrade and no HTTP/2: this is
deliberately the simplest framing that satisfies C7 (in-process termination, no intermediary) and
needs no HTTP upgrade dance between two servers that already mutually authenticated at the TLS
layer.

```
frame_bytes = uint32-le( len( cbor(FedFrame) ) ) ‖ cbor(FedFrame)
FedFrame = { op: FedOp, id: uint, body: bstr }   ; body is nested CBOR, opaque at the frame layer —
                                                   ; mirrors the c2s Frame (rendezvous-protocol-v1 §1)
```

Task [2.4](../tasks/phase-2/2.4-s2s-mtls-link.md) implements this framing over the mTLS
listener/dialer; this task (2.2) only fixes the shape.

All 32-byte keys are encoded as **CBOR byte strings** (major type 2), not integer arrays, exactly
like the c2s protocol.

**Frame ceiling: `MAX_FRAME_LEN = 1 MiB`** (`apps/rendezvous/src/federation/link.rs`). This is
enforced on the wire's u32-LE length prefix *before* any receive buffer is allocated — even an
already-mTLS-authenticated peer must not be able to force an unbounded allocation merely by
sending a large length prefix ahead of a short or absent body (task 2.4/3.7). The **same constant**
is reused, defense-in-depth, as the ceiling on a decoded `FedRoute.envelope`'s own byte length
(`fed_route`'s handler, task 2.8): a compliant peer's frame already can't exceed `MAX_FRAME_LEN` on
the wire, so this second check only ever fires for a non-compliant peer or a caller that built the
request some other way (e.g. a direct unit test) — the load-bearing enforcement is the wire-level
length-prefix check, not this one. There is one constant, not two independently-tunable limits.

**Default federation port: `8444`.** Chosen adjacent to c2s's WSS default (`8443`, see
[rendezvous-protocol-v1.md §1](./rendezvous-protocol-v1.md#1-transport--framing)) so both listeners
can run on the same host with no config edit and no ambiguity about which port is which. It is
**not an IANA-registered service port**; operators are free to override it via `federation.bind` /
`MERIDIAN_RENDEZVOUS_FEDERATION__BIND` (see the deployment note in
[deployment.md §9.2](../operations/deployment.md#92-config-surface-deliberately-small)).

### `FedOp` is its own enum

`FedOp` is a **distinct enum from the c2s [`Op`](./rendezvous-protocol-v1.md)**, never a reuse of
it. This is a deliberate design choice, not an oversight: the c2s `serve` loop only ever decodes
`Op`, never `FedOp`, so there is no shared enum a client-facing connection could exploit to
nominally speak a federation op. A federation listener, symmetrically, only ever decodes `FedOp`.
The two planes are structurally incapable of being confused for one another.

### `Frame.id` semantics

`id = 0` is **reserved for `FedHello`**, exchanged once by each side immediately after the mTLS
handshake completes — mirroring `Challenge`'s `id = 0` role in the c2s protocol, though `FedHello`
is a two-way exchange (each side sends its own), not a server-issued challenge.

Every other frame's `id` is chosen by whichever side emits the *initiating* frame
(`FedFetchBundle`, `FedRoute`, `FedReachability`) and is echoed back in the reply or `FedErr`; an
`id` only needs to be unique among that side's own outstanding requests on this link.

Unlike c2s, s2s has **no client/server asymmetry** to reserve a shared id space around — either
peer may initiate a request toward the other over the same full-duplex link (both A→B and B→A
federated deliveries and fetches are legitimate). There is no single "`id = 0` means unsolicited
push" story beyond `FedHello` itself; every other frame is either an initiating request (id chosen
by its sender) or a reply/error echoing that same id.

## 2. Ops

| `op` | direction | body | purpose |
|---|---|---|---|
| `Hello` | both, once, `id=0` | `{ v: uint, domain: tstr }` | opens every federation link |
| `FetchBundle` | initiator→peer | `{ target: bstr[32], requesting_server: tstr }` | fetch a bundle for an account the peer's org is authoritative for |
| `Bundle` | peer→initiator | `{ bundle: PrekeyBundle }` | the requested bundle |
| `Route` | either→peer | `{ to: bstr[32], from: bstr[32], envelope: bstr }` | route an opaque envelope across the boundary |
| `Reachability` | initiator→peer | `{ target: bstr[32] }` | is a device for `target` connected right now? |
| `Reachable` | peer→initiator | `{ connected: bool }` | reachability reply |
| `Err` | either→peer | `{ code: tstr, msg: tstr }` | structured error, echoes the failed request's `id` |

`PrekeyBundle` is the same type as the c2s protocol's — see
[rendezvous-protocol-v1.md §1](./rendezvous-protocol-v1.md#1-transport--framing) — reused
verbatim, not redefined for federation.

**`FedRoute` is fire-and-forget on success.** A successful route produces no reply frame at all
(silent success, matching the "opaque, one-way push" nature of `Deliver` on the client side);
failure is reported only via `FedErr` echoing the route's `id`. There is deliberately no
`FedRouteOk` — do not add one.

**An offline recipient at the receiving org is now a durable queue, not a drop**
([T07](../architecture/features/07-offline-mailbox.md)/[8.6](../tasks/phase-8/8.6-fed-route-mailbox-enqueue.md)).
Before task 8.6, `handle_fed_route` returned `Ok(())` unconditionally, regardless of whether the
target was actually connected — a route to an offline recipient was silent, permanent message
loss. It now enqueues into the recipient's ciphertext mailbox (same TTL/quota-aware logic as the
local route path, [8.5](../tasks/phase-8/8.5-local-route-mailbox-enqueue.md)) and still
returns `Ok(())` — this is **not** a wire change and does **not** reopen "no `FedRouteOk`": the
receiving org's own `mailbox.ttl_days`/`quota_mb` config decides the outcome, invisibly to the
sending org, exactly like every other server-local policy this protocol already keeps opaque to
the peer. Two consequences, deliberately accepted:
- **Sender-visible framing gap.** The dialing side's own client sees the same optimistic
  `RouteOk{delivered:true, queued:false}` whether the message was actually delivered live or
  queued at the foreign org — the "queued at org-b" sender-visible message the feature spec
  describes is truthfully achievable only for a **same-server** route (§4 of
  [rendezvous-protocol-v1.md](./rendezvous-protocol-v1.md)); `meridian-admin mailbox dump` at the
  receiving org is the real, honest proof for the federated case. This is a **widening** of the
  already-accepted `ROUTE_REPLY_GRACE` false-positive residual immediately below, not a new one.
- **Quota is a legitimate exception to fire-and-forget.** If enqueueing would exceed the
  recipient's mailbox quota, `handle_fed_route` returns `Err(FedErr{code: "mailbox_full"})` instead
  of `Ok(())` — see §4. `ttl_days == 0` at the receiving org (mailbox genuinely disabled) is the one
  case that still silently drops, matching pre-8.6 behavior exactly: there is nowhere durable to
  put the message, and (per the architect consult behind 8.3/8.5/8.6) `ttl_days == 0` has no
  wire-visible signal of its own.

**The fixed-latency-tax / reply-wait this implies, and its measured bound (task 3.20).** Because
there is no `FedRouteOk`, the dialing side (`route_foreign`,
`apps/rendezvous/src/federation/outbound.rs`) has no positive signal that a route succeeded — it
can only wait a bounded window (`ROUTE_REPLY_GRACE`) for a possible `FedErr` and, if nothing arrives
in time, treat that as success. Every successful federated route pays this wait as a fixed latency
tax before the client's request resolves, and the window necessarily trades off against a real
residual: a genuine `FedErr` that crosses the wire slower than the window (real congestion, an
overloaded peer) is reported to the client as a false-positive delivery confirmation instead. Task
2.8 shipped this window as an unmeasured 500ms guess and recorded the tension as an open follow-up;
task 3.20 measured the real reply-RTT (N=200 samples, over a real two-server mTLS link, isolating
the exact span this window bounds: `p50≈88ms`, `p99≈92ms`, `max≈93ms` — see
`ROUTE_REPLY_GRACE`'s own doc comment in `outbound.rs` for the full measurement, including a
same-implementation finding — missing `TCP_NODELAY` — that explains why this is tens of
milliseconds even on loopback, not fractions of one) and tightened `ROUTE_REPLY_GRACE` to **300ms**
(measured max rounded up, ×3 real-network headroom) accordingly. This narrows, but by design does
**not** close, the false-positive residual described above — closing it outright would need this
section's "do not add a `FedRouteOk`" decision reopened via an ADR, not a unilateral change to the
window alone.

**`FedHello.domain` and `FedFetchBundle.requesting_server` are self-asserted / informational only,
never authoritative.** Both exist purely as diagnostic/logging aids (e.g. surfacing a
domain-mismatch warning in an operator's logs). The mTLS peer identity established at the
transport layer (ADR 0017 (a)) is authoritative for every policy, routing, and rate-limit decision
(C5) — these two string fields are never consulted for any such decision.

**Reserved, unimplemented: `contact_token`.** [wire-protocol.md §4](./wire-protocol.md#4-server--server-federation-mtls)
(pre-this-doc) named an optional `contact_token{issuer_sig, audience, exp}` field on first-contact
routes when the target org's policy requires it. Contact tokens are explicitly **out of scope**
for this task and for Feature 06 in general — they are deferred to T08/T14, tracked today via
[2.10's](../tasks/phase-2/2.10-message-request-gate.md) "Out: contact tokens and PoW stamps
(explicitly T08/T14)". The name is recorded here as reserved; there is no corresponding field on
`FedRoute` or any other type in `apps/proto/src/fed.rs`, and none should be added without going
through those tasks.

## 3. Versioning

`FED_VERSION = 1` (`apps/proto/src/fed.rs`), carried in `FedHello.v`. A wire change to any
federation body type is a `meridian-proto` change: bump `FED_VERSION`, prefer capability
negotiation over a breaking change, and regenerate `test-vectors/federation-v1.json`
byte-identically (wire-protocol.md's versioning convention, §1).

## 4. Error codes

Stable `code` strings used in `FedErr` (`apps/proto/src/fed.rs::fed_error_codes`):

| code | meaning | emitted by |
|---|---|---|
| `policy_denied` | federation to/from this origin is closed, or the origin is not on an allowlist policy's list | [2.6](../tasks/phase-2/2.6-federation-policy-limits.md) |
| `rate_limited` | federation-edge rate limits exceeded (keyed per ADR 0017 C5) | [2.6](../tasks/phase-2/2.6-federation-policy-limits.md) |
| `not_found` | `FetchBundle`'s target is not an account this org is authoritative for | [2.7](../tasks/phase-2/2.7-federated-prekey-fetch.md) |
| `bad_request` | malformed frame or body | any handler |
| `mailbox_full` | `Route`'s target is offline and enqueueing would exceed their mailbox quota — a legitimate exception to fire-and-forget-on-success (§2) | [8.6](../tasks/phase-8/8.6-fed-route-mailbox-enqueue.md) |

**`FetchBundle`'s per-account rate-limit axis is keyed on `req.target`, not on an asserted
`from`.** §0/ADR 0017 C5 says the "origin account" rate-limit axis keys on the asserted `from` —
but `FedFetchBundle`'s body (§2) carries no requesting-account field at all, unlike `FedRoute`,
which does carry `from`. There is nothing else request-shaped to key a per-account dimension on,
so `handle_fed_fetch` (task 2.7) instead keys it on `req.target` — the account *being fetched* —
bounding how many times per minute a single foreign origin may query for the *same* target, on top
of the aggregate per-origin budget (`rate_limited`, above). This is a deliberate reading of an
underspecified wire shape, not a wire change: `FedFetchBundle` is reused verbatim. **Residual:**
keying on `req.target` bounds repeated queries against *one* target, but gives no defense against a
malicious/compromised origin spraying requests across many distinct (real or fabricated) targets —
each fresh target starts its own per-account counter at zero. This is not a hard hole: the 256-bit
keyspace already makes target-guessing useless for enumeration, and the aggregate per-origin budget
still bounds total throughput regardless of how targets are varied — but the per-account
dimension's real guarantee is narrower than "bounds one origin's total fetch volume": it only
bounds volume against a single repeatedly-queried target (see
`apps/rendezvous/src/federation/inbound.rs`'s module doc comment and
`federation_fetch.rs::bs_federation_edge_rate_limit_trips_through_the_real_path` for the
demonstrating test).

## 5. What two federating orgs may learn

This restates the ceiling from
[anonymity-and-retention.md's exposure table](../security/anonymity-and-retention.md#what-is-exposed-and-to-whom-never-paper-over-this)
verbatim in substance, specialized to the federation link:

> **The two federating orgs see who-signals-whom across the boundary, per request.** They never
> see message or media content. `FedReachability` is **per-request only** — there is no
> persistent cross-org presence subscription (matching [system design §3.4](../architecture/system-design.md#34-presence-and-reachability):
> "Rendezvous servers exchange *per-request* reachability... rather than subscription-based
> presence feeds across the federation boundary — presence fan-out is a notorious metadata
> amplifier"). `FedRoute.envelope` is opaque end to end — a federation link never decodes it, the
> same invariant `tools/lint-no-serde-on-blob.sh` enforces for the c2s `Route`/`Deliver` path.

This is the accepted A2 bilateral-trust model from the [threat model](../security/threat-model.md)
and [ADR 0017](../adr/0017-federation-trust-boundary.md)'s residual risks — not a new exposure
introduced by this doc.

## 6. Known simplifications (task 2.2)

- **No behavior yet.** This doc and `apps/proto/src/fed.rs` fix the wire shape only; there is no
  listener, dialer, discovery, policy, or handler code — those land in
  [2.4](../tasks/phase-2/2.4-s2s-mtls-link.md)–[2.8](../tasks/phase-2/2.8-federated-route-reachability.md).
- **No c2s changes (as of this task).** `wire-protocol.md §2`'s reconciliation to the canonical
  `Deliver{from, blob}` naming, and the `Fetch.hint`/`RouteBody.to_hint` fields, were
  [2.3](../tasks/phase-2/2.3-c2s-federation-extension.md)'s job, not this task's — 2.3 has since
  landed them.
- **`contact_token` is reserved, not implemented** — see §2 above.
- **No cryptographic s2s provenance attestation.** `from` is server testimony, not a signature —
  ADR 0017 (b) decision C, rejected for v1; see ADR 0017 for the full reasoning and residual risk
  R1.
