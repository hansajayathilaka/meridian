<!-- Source: p2p-comms-design.md §8 ADR-4. -->
> **Nav:** [ADR index](./README.md) · [system design](../architecture/system-design.md)

# ADR 0004: Group messaging — pairwise fan-out first, MLS (RFC 9420) as the group protocol

**Status:** Proposed (groups are explicitly secondary) · **Options:** (A) pairwise Double-Ratchet fan-out; (B) Signal-style sender keys; (C) **MLS (chosen for target state)**.

**Trade-offs:** A is O(N·devices) per message — fine to ~15 members, unusable beyond; strongest properties, zero new machinery, ships almost free with 1:1. B scales linearly and is proven, but PCS on member removal requires full sender-key redistribution ≈ pairwise cost at the worst moment. C gives O(log N) commits, real PCS on membership change, an IETF standard with growing implementations (OpenMLS fits the Rust core), and its SFrame keying story covers future group calls — its cost is a Delivery Service role (ordering/commit sequencing) that our rendezvous must take on for group state, plus library maturity risk. **Decision:** ship A for small groups in Phase 2 as a stopgap wearing an explicit size cap, adopt C as the group substrate in Phase 3; never build B as a third system. **Consequences:** rendezvous grows a strictly-ordered, content-blind group-commit log (still ciphertext-only); group metadata (membership visible to members, delivery patterns to the DS) documented as a limitation.

