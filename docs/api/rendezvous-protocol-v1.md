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
| `Fetch` | C→S | `{ target: bstr[32], hint?: tstr, tamper?: bool }` | fetch a bundle by **exact** key |
| `Bundle` | S→C | `{ bundle: PrekeyBundle }` | the requested bundle |
| `Route` | C→S | `{ to: bstr[32], to_hint?: tstr, blob: bstr }` | route an opaque envelope |
| `RouteOk` | S→C | `{ delivered: bool }` | routed to a live peer |
| `Deliver` | S→C | `{ from: bstr[32], blob: bstr }` | a delivered envelope |
| `TurnReq` | C→S | `{}` | request ephemeral TURN credentials (T05) |
| `TurnGrant` | S→C | `{ urls: [*tstr], username: tstr, credential: tstr, ttl_secs: uint, realm: tstr }` | a minted TURN credential, distinct per request |
| `Err` | S→C | `{ code: tstr, msg: tstr }` | structured error (codes below) |

`PrekeyBundle = { v, account_pub: bstr[32], spk: bstr[32], spk_sig: bstr[64], otks: [*bstr[32]], otk_sigs: [*bstr[64]], device_record?: bstr }` — every `*_sig` is `Ed25519(account_pub)` over the corresponding public key. `device_record` is opaque and account-signed (T13). ≤100 one-time prekeys.

**Error codes:** `auth_required`, `auth_failed`, `replay`, `admission_denied`, `not_found`, `not_connected`, `rate_limited`, `bad_bundle`, `bad_request`, `turn_unavailable`, `fed_denied`, `fed_unreachable`, `not_found_at_hint` (the last three are T06/[2.3](../tasks/phase-2/2.3-c2s-federation-extension.md) additions — see §4).

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

### Federation hints (T06)

`Fetch.hint` and `RouteBody.to_hint` are the wire encoding of the routing invariant *client → own
server → foreign server → client*: a client names a foreign target by attaching the domain part of
its `mrd1:…@domain` ID as `hint`/`to_hint`, telling its **own** server that `target`/`to` may not be
an account it holds and, if not, to forward across the federation boundary instead of returning
`not_found`. Both fields are a **plain domain string** — never a parsed `mrd1:` ID. The server must
not decode identity strings (that needs `meridian-identity`, which would break
`tools/lint-server-no-core.sh`); parsing an ID into key + hint stays entirely client-side
(`apps/identity/src/id.rs::validate_hint`). Absent for a same-server operation; omitted from the
wire entirely when not present, so existing hint-less clients are byte-identical to before this
addition. This doc fixes the field shape only — this task (2.3) adds **no** server behaviour that
reads either field; the server consuming them to actually forward is
[2.7](../tasks/phase-2/2.7-federated-prekey-fetch.md)/[2.8](../tasks/phase-2/2.8-federated-route-reachability.md)'s
job, and the s2s side of that forward is specified in
[federation-protocol-v1.md](./federation-protocol-v1.md).

Three new error codes cover the federated outcomes a hint can produce, distinct from the local
`not_found`/`rate_limited` cases above: `fed_denied` (this org's federation policy refuses the
hinted domain), `fed_unreachable` (the hinted server could not be reached at all — discovery or
dial failure), and `not_found_at_hint` (the hinted server was reached but doesn't hold the target —
the stale-hint case). The stale-hint case is explicitly a reachability/UX outcome, never a security
warning ([ADR 0001](../adr/0001-identity-scheme.md) consequences) — a client presents it as "unreachable at hint," not as a trust warning.

**Federated `Deliver.from`** ([ADR 0017](../adr/0017-federation-trust-boundary.md) (b)/C2/C6): the
shape is unchanged — no new field — but for a route that crossed a federation boundary, `from` is
the value the *foreign* server asserted in its `FedRoute{from}`, relayed verbatim by this server
exactly as it already does for a purely local route. The client's `sender_pub != from` check
([ADR 0016](../adr/0016-envelope-deniability.md) residual R4, scope-corrected by ADR 0017 C6) does
not weaken: it now compares against server testimony one hop further from the client, still never a
cryptographic proof.

## 4a. TURN credentials (T05)

`TurnReq{}` asks the server to mint an **ephemeral, per-session** TURN credential for the connecting client; the reply is `TurnGrant`. This is the [coturn shared-secret / REST mechanism](https://github.com/coturn/coturn/blob/master/README.turnserver) (`use-auth-secret`), so **no static TURN secret ever reaches a client** ([webrtc-nat-traversal](../../.claude/skills/webrtc-nat-traversal/SKILL.md) invariant 4, system-design §5.4):

```
username   = "<expiry-unix>:<nonce-hex>"      ; expiry = now + ttl_secs; nonce is fresh per mint
credential = base64( HMAC-SHA1( shared_secret, username ) )
```

coturn — sharing the *same* secret (`static-auth-secret` == rendezvous `[turn].secret`) — recomputes the HMAC over the presented username and admits the allocation only while `now < expiry`. Two properties matter:

- **Expiry** is embedded in the username, so the TTL is enforced by coturn with **no server-side session state** (the rendezvous stays near-stateless, ADR-8).
- **Distinct per mint**: a fresh random nonce per mint makes every credential unique, so a captured credential cannot be used to forge allocations under a *different* username. It does **not** by itself prevent reuse of that one captured credential: within its own TTL window, coturn's `user-quota` (`infra/coturn/turnserver.conf`) bounds — but does not reject outright — how many allocations it can mint before expiry (feature-05 acceptance: *distinct grants, quota-bounded reuse*; true reuse-rejection at the wire level is proven separately, task 1.25/1.27 (the real-coturn netns matrix, split from what was originally task 1.16 via 1.23).

`urls` is the ladder in preference order — `turn:…?transport=udp`, `turn:…?transport=tcp`, then `turns:…:443?transport=tcp` (the hostile-egress last resort). A server with **no** relay configured (empty secret — a dev server, or air-gapped with no TURN) replies `turn_unavailable`; the client then uses the host/STUN ladder only and `meridian doctor` names the blocked path. Minting is authenticated (post-`AuthOk`) and rate-limited per account (`turn_per_account_per_min`). The mint rate is exported as the allowlisted `meridian_turn_credentials_minted_total` (§9.4). Client side: `meridian_signaling::SignalingClient::request_turn_credentials`.

## 5. Config surface (the §9.2 subset)

TOML; every field has a default (see [`meridian-rendezvous` `config`](../../apps/rendezvous/src/config.rs)):

```toml
[server]
domain = "chat.example"          # folded into the auth challenge
bind = "127.0.0.1:8443"
admission = "open"               # open | invite
invite_tokens = []               # for invite admission
allow_test_tamper = false        # TEST HOOK — must be false in production
allow_test_route_tamper = false  # TEST HOOK — must be false in production. UMBRELLA gate for
                                 # tampering with the routed path (tasks 1.28 + 1.32). Inert unless
                                 # built with `--features test-tamper-hook`, AND additionally
                                 # requires allow_test_tamper, AND on its own arms nothing — each
                                 # attack has its own flag below. Unlike allow_test_tamper these
                                 # have NO per-request opt-in: once on, they affect EVERY routed
                                 # blob for EVERY user, while still replying
                                 # route_ok{delivered:true}.
allow_test_route_rewrite = false      # 1.28: flip a byte inside a routed blob in transit
allow_test_route_spoof_from = false   # 1.32: forge Deliver.from (the server asserts it itself)
allow_test_route_replay = false       # 1.32: re-deliver a blob byte-identically
allow_test_route_drop = false         # 1.32: swallow a blob but still ack delivered = true
allow_test_route_reorder = false      # 1.32: release blobs out of order
allow_test_route_cross_deliver = false # 1.32: deliver one session's envelope to the wrong recipient
database_url = "sqlite://rendezvous.db"   # only used with the `sqlite` feature

[limits]                         # anti-abuse, fixed one-minute windows
auth_per_ip_per_min = 60
fetch_per_account_per_min = 120
route_per_account_per_min = 600
turn_per_account_per_min = 60

[turn]                           # ephemeral TURN credential minting (T05, §5.4)
secret = ""                      # == coturn static-auth-secret; EMPTY ⇒ minting disabled. Out of band.
realm = "localhost"              # coturn realm, echoed to the client
urls = [                         # the candidate ladder, preference order
  "turn:127.0.0.1:3478?transport=udp",
  "turn:127.0.0.1:3478?transport=tcp",
  "turns:127.0.0.1:443?transport=tcp",
]
ttl_secs = 120                   # credential lifetime (short); reuse bounded by coturn user-quota
```

## 6. Metrics

`GET /metrics` exposes **only** the allowlisted names (`tools/metrics-allowlist.txt`, §9.4): `meridian_connections_active`, `meridian_envelopes_routed_total`, `meridian_prekey_pool_depth`, `meridian_turn_credentials_minted_total`. `GET /healthz` is a liveness probe. Never per-user sizes, contact-graph, or content metrics.

## 7. Storage & persistence

Storage is a trait ([`store.rs`](../../apps/rendezvous/src/store.rs)). The MVP default is **in-memory** (fast, hermetic tests; losing it costs *reachability* only — clients republish on reconnect, ADR-8). A **SQLite/sqlx** backend is available behind the `sqlite` feature (stack.md §3); Postgres is a later flag. What an admin with the DB learns is bounded to the [data model](../architecture/data-model.md): which keys registered and their public prekeys — no content, no contact graph.

## 8. Known MVP simplifications (T02)

- TLS is proxy/VIP-terminated in this increment (ws on the bind address); direct rustls termination is a follow-up.
- Persistence defaults to in-memory; the sqlx/SQLite impl is feature-gated and stores each bundle as one CBOR blob rather than the fully normalized [data-model](../architecture/data-model.md) columns. **Resolved, re-deferred to T07** ([2.3](../tasks/phase-2/2.3-c2s-federation-extension.md)): Feature 06 adds no new persisted state of its own — the federation map, policy and allowlist are config (not DB rows), rate limits are in-memory counters, reachability is live `Registry` state, and the bundle a federated fetch serves is the same blob already stored today. [T07](../architecture/features/07-offline-mailbox.md)'s mailbox is the first feature that needs per-envelope rows, TTL sweeps and quota accounting — the first actual consumer a normalized schema would have. Normalized schema + Postgres remain out of scope until then.
- Prekey **secret** lifecycle (persistence, rotation) is deferred to T03 (X3DH); T02 publishes real, signed public prekeys. *TODO: confirm in T03.*
- Offline delivery returns `not_connected`; the ciphertext mailbox is T07.
