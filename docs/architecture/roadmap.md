# Phased Roadmap & Feature Index

<!-- Source: p2p-comms-design.md §11 + tasks/T00-INDEX. -->
> **Nav:** [docs index](../INDEX.md) · [system design](./system-design.md) · [features](./features/) · [test strategy](../testing/strategy.md)

Every feature ships as a runnable increment — each spec under [features/](./features/) ends in a
demo you can execute at sign-off. Trust-critical substrate comes first; convenience later.

## Feature specs (priority order)

| # | Feature | Working output at sign-off | Depends on |
|---|---------|----------------------------|------------|
| [01](./features/01-identity-keystore-core.md) | Identity & Keystore Core | CLI mints/parses/verifies `mrd1:` IDs + QR | — |
| [02](./features/02-rendezvous-mvp.md) | Rendezvous Server MVP | Two CLIs register & fetch verified prekey bundles | 01 |
| [03](./features/03-e2ee-messaging-relayed.md) | E2EE Messaging (relayed) | Two CLIs chat; server sees only opaque blobs | 02 |
| [04](./features/04-p2p-session-substrate.md) | P2P Session Substrate | Chat goes P2P; survives server shutdown | 03 |
| [05](./features/05-nat-traversal-relay-policy.md) | NAT Traversal & Relay Policy | Session across symmetric NATs; `relay-only` hides IPs | 04 |
| [06](./features/06-cross-org-federation.md) | Cross-Org Federation | Full cross-org walkthrough on two stacks | 04 |
| [07](./features/07-offline-mailbox.md) | Offline Ciphertext Mailbox | Offline peer gets message on reconnect; DB ciphertext-only | 03, 06 |
| [08](./features/08-verification-trust.md) | Verification & Contact Trust | Simulated MITM fails closed; safety-number QR | 03 |
| [09](./features/09-file-transfer.md) | File Transfer Stream | 1 GiB transfer, killed mid-way, resumes + verifies | 04 |
| [10](./features/10-av-calls-screenshare.md) | Voice / Video / Screenshare | Cross-org video call, live relay fallback | 05, 06 |
| [11](./features/11-browser-desktop-clients.md) | Browser & Desktop Clients | Browser tab ↔ CLI chat + file transfer | 04–09 |
| [12](./features/12-mobile-clients.md) | Mobile Clients | Android/iOS chat + call, push-wake delivery | 10, 11 |
| [13](./features/13-multi-device.md) | Multi-Device | 2nd device by QR; ghost-device insertion detected | 08, 11 |
| [14](./features/14-selfhosting-ops-kit.md) | Self-Hosting Ops Kit | One-command stack; dashboard; air-gapped install | 06, 07 |
| [15](./features/15-location-stickers.md) | Location & Stickers | Live location on map; signed sticker pack P2P | 09, 11 |
| [16](./features/16-tier2-tunnels.md) | Tier-2 Tunnels (SSH / fs) | `ssh` into a NAT'd headless box via `meridian tunnel` | 09 |

## Phasing (from the design)

| D. Blockchain/ENS-style name→key registry | consensus system | good | good |

**Decision: C.** A gives servers key-substitution power — disqualifying under A2. B forces a DHT into v1's critical path — disqualifying for air-gapped enterprise. D imports a consensus dependency and its ops burden onto a 2–5-person team for what is, at bottom, a petname convenience; org directory attestations (§3.5) capture most of the value without it. **Consequences:** IDs are long/opaque → invest in QR + petname UX; hint staleness is a real failure mode → ID re-issue flow and (Phase 4) DHT hint-resolution fallback; server migration is user-visible but security-neutral. **Revisit** if a naming layer becomes a hard product requirement.

### ADR-2: Federation mechanism — server-to-server signaling over mTLS, DHT deferred

**Status:** Proposed · **Options:** (A) Kademlia-style DHT for discovery + hole-punching relays; (B) **federated s2s signaling, DNS-SRV/static-map discovery (chosen)**; (C) rendezvous hashing across a shared server list; (D) gossip mesh among servers.

**Trade-offs:** A maximizes decentralization but: Sybil/eclipse pressure on availability, lookup metadata broadcast to strangers, poor mobile churn behavior, and it degenerates into "a hard-to-operate static map" in air-gapped two-org deployments — the primary deployment! C requires globally consistent membership (a coordination problem federation is supposed to avoid) and reshuffles on membership change. D adds convergence complexity with no lookup benefit at realistic org counts (2–200). B matches email/Matrix operational intuition, keeps metadata bilateral (only the two involved orgs observe a cross-org contact), needs no shared state, and air-gaps trivially (static federation map + private CA). **Decision: B**, with the ID scheme deliberately transport-agnostic so a PKARR/mainline-DHT resolver can be added in Phase 4 for server-less consumer use **as an addition, not a migration**. **Consequences:** reachability of `K_B` depends on `chat.org-b` being up (mitigate: multi-hint IDs, mailbox retries); federation abuse handled bilaterally (rate limits, allowlists) rather than by global consensus.

### ADR-3: E2EE messaging protocol — X3DH + Double Ratchet at the application layer


## Parallel tracks for a small team
Track A (protocol): 01→03→08→13 · Track B (transport): 04→05→09→10→16 ·
Track C (infra): 02→06→07→14 · Track D (clients): 11→12→15.
Features 01–04 are the critical path everyone converges on first.
