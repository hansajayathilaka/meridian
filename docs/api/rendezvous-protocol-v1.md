<!-- Source: T02 (feature 02-rendezvous-mvp). Client↔rendezvous framing, concretized. -->
> **Nav:** [docs index](../INDEX.md) · [api reference](./README.md) · [wire protocol](./wire-protocol.md) · [identity format](./identity-format.md) · [data model](../architecture/data-model.md) · [ADR 0008](../adr/0008-infra-topology.md)

# Rendezvous Protocol — v1 (client ↔ server)

Concrete framing for the T02 signaling server, normative companion to
[wire-protocol.md §2](./wire-protocol.md#2-client--rendezvous-wss). It specifies exactly what
`meridian-rendezvous` speaks and what [`meridian-signaling`](../../apps/signaling) implements.
Encoding is **deterministic CBOR** (RFC 8949) via `ciborium`; the shared types live in
[`meridian-proto`](../../apps/proto) so client and server cannot drift.

The server's whole security posture is the [§2.3 "cannot" list](../architecture/system-design.md#23-responsibility-boundaries-the-cannot-list): it routes opaque signed blobs and stores public key material, and it holds no plaintext and no session/ratchet code. Its one cryptographic act is **verifying** a client's Ed25519 auth signature.

## 1. Transport & framing

A client opens a WebSocket to the server (`wss://` in production; TLS is terminated by the deployment's reverse proxy / VIP per [ADR-8](../adr/0008-infra-topology.md), or directly in a later increment). Every message is a **binary** WebSocket frame carrying one CBOR `Frame`:

```
Frame = { op: tstr, id: uint, body: bstr }   ; body is nested CBOR, opaque at the frame layer
```

- `op` selects how `body` decodes (table below).
- `id` is a client-chosen request id **echoed** in the reply. Server-initiated frames (the opening challenge, pushed deliveries) use `id = 0`.
- `body` is a nested CBOR byte string, so the frame layer never needs to understand payload shape — and the server can forward a routed blob without decoding it.

All 32-byte keys and 64-byte signatures are encoded as **CBOR byte strings** (major type 2), not integer arrays.

| `op` | direction | body | purpose |
|---|---|---|---|
| `Challenge` | S→C | `{ nonce: bstr[32], server_time: uint, server_domain: tstr }` | opens every connection |
| `Auth` | C→S | `{ account_pub: bstr[32], sig: bstr[64], invite?: tstr, max_bundle_v: uint }` | prove key control + register |
| `AuthOk` | S→C | `{ server_domain: tstr }` | auth accepted |
| `Publish` | C→S | `{ bundle: PrekeyBundle }` | store this account's bundle |
| `PublishOk` | S→C | `{ accepted_otks: uint }` | stored |
| `Fetch` | C→S | `{ target: bstr[32], tamper?: bool }` | fetch a bundle by **exact** key |
| `Bundle` | S→C | `{ bundle: PrekeyBundle }` | the requested bundle |
| `Route` | C→S | `{ to: bstr[32], blob: bstr }` | route an opaque envelope |
| `RouteOk` | S→C | `{ delivered: bool }` | routed to a live peer |
| `Deliver` | S→C | `{ from: bstr[32], blob: bstr }` | a delivered envelope |
| `Err` | S→C | `{ code: tstr, msg: tstr }` | structured error (codes below) |

`PrekeyBundle = { v, account_pub: bstr[32], spk: bstr[32], spk_sig: bstr[64], otks: [*bstr[32]], otk_sigs: [*bstr[64]], device_record?: bstr }` — every `*_sig` is `Ed25519(account_pub)` over the corresponding public key. `device_record` is opaque and account-signed (T13). ≤100 one-time prekeys.

**Error codes:** `auth_required`, `auth_failed`, `replay`, `admission_denied`, `not_found`, `not_connected`, `rate_limited`, `bad_bundle`, `bad_request`.

## 2. Handshake & registration

1. On connect the server sends `Challenge` with a fresh single-use `nonce`.
2. The client replies `Auth` with `sig = Ed25519(account_key, nonce ‖ server_domain)`. Folding the domain in stops a signature captured on one server from replaying against another (wire-protocol §2).
3. The server verifies the signature **against the connection's own nonce**. Because each connection gets a fresh nonce, an `Auth` frame captured from another connection fails here — this is the replay defense. The account row is created on first successful auth.
4. **Admission** (`open | invite`) is checked before registration; OIDC gating (§3.2) is a future admission variant behind the same trait. Admission is *who may register here*, never part of end-to-end security.

## 3. Bundles & anti-enumeration

`Fetch` takes an **exact, full** 32-byte key. There is deliberately **no** prefix, range, or search operation — account keys are 256-bit and unguessable, so there is no namespace to walk (system-design §3.5). A near-miss key simply returns `not_found`. Per-account fetch rate limits bound quiet enumeration/DoS.

**The client's mandatory check (the point of T02):** after `Fetch`, the client verifies that the returned bundle's `account_pub` equals the requested key **and** that every `spk_sig`/`otk_sig` verifies under it. A bundle that verifies under any *other* key — the canonical malicious-server substitution — is a **hard error**, never a downgrade ([system-design §3.3 step 4](../architecture/system-design.md#33-cross-server-rendezvous-with-no-central-directory)). This lives in `meridian_signaling::verify_bundle` and is exercised by the [mitm-sim harness](../../harnesses/mitm-sim). OTK *consumption* during X3DH is T03; T02 returns the stored bundle intact.

## 4. Routing

`Route{to, blob}` delivers `blob` verbatim to every live connection for `to` as `Deliver{from, blob}`, and replies `RouteOk{delivered:true}`; an offline recipient is `not_connected` (the ciphertext mailbox is [T07](../architecture/features/07-offline-mailbox.md)). The server **never** decodes `blob` — it is `OpaqueBlob` end to end, enforced by `tools/lint-no-serde-on-blob.sh`.

## 5. Config surface (the §9.2 subset)

TOML; every field has a default (see [`meridian-rendezvous` `config`](../../apps/rendezvous/src/config.rs)):

```toml
[server]
domain = "chat.example"          # folded into the auth challenge
bind = "127.0.0.1:8443"
admission = "open"               # open | invite
invite_tokens = []               # for invite admission
allow_test_tamper = false        # TEST HOOK — must be false in production
database_url = "sqlite://rendezvous.db"   # only used with the `sqlite` feature

[limits]                         # anti-abuse, fixed one-minute windows
auth_per_ip_per_min = 60
fetch_per_account_per_min = 120
route_per_account_per_min = 600
```

## 6. Metrics

`GET /metrics` exposes **only** the allowlisted names (`tools/metrics-allowlist.txt`, §9.4): `meridian_connections_active`, `meridian_envelopes_routed_total`, `meridian_prekey_pool_depth`. `GET /healthz` is a liveness probe. Never per-user sizes, contact-graph, or content metrics.

## 7. Storage & persistence

Storage is a trait ([`store.rs`](../../apps/rendezvous/src/store.rs)). The MVP default is **in-memory** (fast, hermetic tests; losing it costs *reachability* only — clients republish on reconnect, ADR-8). A **SQLite/sqlx** backend is available behind the `sqlite` feature (stack.md §3); Postgres is a later flag. What an admin with the DB learns is bounded to the [data model](../architecture/data-model.md): which keys registered and their public prekeys — no content, no contact graph.

## 8. Known MVP simplifications (T02)

- TLS is proxy/VIP-terminated in this increment (ws on the bind address); direct rustls termination is a follow-up.
- Persistence defaults to in-memory; the sqlx/SQLite impl is feature-gated and stores each bundle as one CBOR blob rather than the fully normalized [data-model](../architecture/data-model.md) columns. *TODO: confirm normalized schema + Postgres in T06/T07.*
- Prekey **secret** lifecycle (persistence, rotation) is deferred to T03 (X3DH); T02 publishes real, signed public prekeys. *TODO: confirm in T03.*
- Offline delivery returns `not_connected`; the ciphertext mailbox is T07.
