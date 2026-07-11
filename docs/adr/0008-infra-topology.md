<!-- Source: p2p-comms-design.md §8 ADR-8. -->
> **Nav:** [ADR index](./README.md) · [system design](../architecture/system-design.md)

# ADR 0008: Infra topology — per-org rendezvous+TURN pair, no shared global tier

**Status:** Proposed · **Options:** (A) each org runs rendezvous + TURN, federating bilaterally **(chosen)**; (B) shared community super-nodes; (C) clients double as relays (mesh).

B recreates a central operator — the thing the design exists to avoid — and a juicy metadata aggregation point. C turns end-user devices into other people's exfiltration-shaped traffic sources; enterprises will (correctly) refuse. A matches the operator model (a small team per org), keeps each org's metadata inside that org, and its cost — every org must actually run two smallish services — is the explicitly accepted price of the whole architecture. HA story: rendezvous is near-stateless (prekeys/mailbox in Postgres or even SQLite+litestream; WebSocket state rebuildable), so active-passive behind a VIP suffices; TURN scales horizontally with DNS.

---
