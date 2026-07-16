<!-- Retroactive record. Phase 0 shipped before this tracker existed; captured here so /start-review-phase
     has a defined scope to review. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 0 — Foundation

**Kind:** build · **Status:** done · **Reviewed by:** Phase 1 (pending)

## Goal
The trust-critical substrate everything else converges on: mint/verify identities, register and fetch
verified prekey bundles, exchange E2EE messages the server can't read, move those sessions P2P, and
survive hostile NATs with a relay-only privacy mode. Matches the design's "features 01→05 critical path".

## Chosen feature(s) / scope
- **T01** Identity & Keystore Core — [spec](../../architecture/features/01-identity-keystore-core.md)
- **T02** Rendezvous Server MVP — [spec](../../architecture/features/02-rendezvous-mvp.md)
- **T03** E2EE Messaging, relayed — [spec](../../architecture/features/03-e2ee-messaging-relayed.md)
- **T04** P2P Session Substrate — [spec](../../architecture/features/04-p2p-session-substrate.md)
- **T05** NAT Traversal & Relay Policy — [spec](../../architecture/features/05-nat-traversal-relay-policy.md)

## Dependency check
None — this is the base. ~12k lines of Rust across 9 crates (`apps/{proto,core,identity,store,crypto,transport,signaling,cli,rendezvous}`).

## Tasks (todo)
- [x] **0.1** Identity & Keystore Core (T01) — [file](./0.1-identity-keystore.md)
- [x] **0.2** Rendezvous Server MVP (T02) — [file](./0.2-rendezvous-mvp.md)
- [x] **0.3** E2EE Messaging, relayed (T03) — [file](./0.3-e2ee-messaging.md)
- [x] **0.4** P2P Session Substrate (T04) — [file](./0.4-p2p-session-substrate.md)
- [x] **0.5** NAT Traversal & Relay Policy (T05) — [file](./0.5-nat-traversal-relay.md)

## Exit criteria
All five features merged to `main` with their acceptance demos. **Met.** Next: `/start-review-phase`.
