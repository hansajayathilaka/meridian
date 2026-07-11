<!-- Source: tasks/T02-rendezvous-mvp.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T02 — Rendezvous Server MVP

**Priority:** P0 · **Design refs:** §2.1, §3.2, §9.1–9.2 · **Depends on:** T01 · **Indicative effort:** 2–3 eng-weeks

## Goal
Stand up the single always-on service: identity-key-authenticated WebSocket sessions, prekey bundle storage/fetch, and opaque envelope routing between *online* clients of one org. This is the smallest server that lets two clients find each other's cryptographic material.

## Scope
In: `meridian-rendezvous` Rust binary; WSS endpoint with challenge–response auth (server sends nonce, client signs with account key); registration (`open | invite-token` admission modes; OIDC gate stubbed behind a trait for later); upload of *signed* prekey bundles (signed prekey + ≤100 one-time prekeys) and retrieval by exact full ID; envelope routing (`route{to: pubkey, blob}` → deliver if connected, else error — mailbox is T07); SQLite storage (Postgres behind a feature flag); per-account and per-IP rate limits; prekey-pool depth metric.
Out: federation (T06), mailbox (T07), presence beyond "connected right now".

## Deliverables
1. Server binary + `Dockerfile`; config file with the §9.2 surface subset.
2. Client-side signaling module in `meridian-core` (connect, auth, publish bundle, fetch bundle **with mandatory signature verification against the requested key — a bundle that verifies under any other key is a hard error**, per §3.3 step 4).
3. OpenAPI-style protocol doc `rendezvous-protocol-v1.md` (envelope framing = CBOR).
4. Integration test: malicious-server harness that serves a substituted bundle → client aborts.

## Working output (demo script)
```
$ docker run -p 443:443 meridian-rendezvous --config demo.toml
$ meridian register --server wss://localhost --id alice.key      # → registered
$ meridian register --server wss://localhost --id bob.key
$ meridian fetch-bundle mrd1:<bob>@localhost                     # → "bundle OK, signed by <bob>, 100 OTKs"
$ meridian fetch-bundle --tamper mrd1:<bob>@localhost            # test flag: server substitutes key
  → FATAL: bundle signature does not match requested identity — refusing to proceed
```

## Acceptance criteria
Auth rejects replayed challenges; fetch by partial/prefix ID is impossible at the API level (anti-enumeration §3.5); the tampered-bundle test fails closed with a non-zero exit; server process holds zero plaintext-content code paths (envelope bodies are `Vec<u8>` end to end — enforced by a lint that the routing module has no serde on blob contents); 5k concurrent WSS connections on a 2-vCPU box.

## Risks / notes
Resist adding features here — every capability this server gains is attack surface and trust creep. The "cannot" column of §2.3 is the review checklist for this task's PRs.
