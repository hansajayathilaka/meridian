<!-- Source: p2p-comms-design.md §8 ADR-2. -->
> **Nav:** [ADR index](./README.md) · [system design](../architecture/system-design.md)

# ADR 0002: Federation mechanism — server-to-server signaling over mTLS, DHT deferred

**Status:** Proposed · **Options:** (A) Kademlia-style DHT for discovery + hole-punching relays; (B) **federated s2s signaling, DNS-SRV/static-map discovery (chosen)**; (C) rendezvous hashing across a shared server list; (D) gossip mesh among servers.

**Trade-offs:** A maximizes decentralization but: Sybil/eclipse pressure on availability, lookup metadata broadcast to strangers, poor mobile churn behavior, and it degenerates into "a hard-to-operate static map" in air-gapped two-org deployments — the primary deployment! C requires globally consistent membership (a coordination problem federation is supposed to avoid) and reshuffles on membership change. D adds convergence complexity with no lookup benefit at realistic org counts (2–200). B matches email/Matrix operational intuition, keeps metadata bilateral (only the two involved orgs observe a cross-org contact), needs no shared state, and air-gaps trivially (static federation map + private CA). **Decision: B**, with the ID scheme deliberately transport-agnostic so a PKARR/mainline-DHT resolver can be added in Phase 4 for server-less consumer use **as an addition, not a migration**. **Consequences:** reachability of `K_B` depends on `chat.org-b` being up (mitigate: multi-hint IDs, mailbox retries); federation abuse handled bilaterally (rate limits, allowlists) rather than by global consensus.

