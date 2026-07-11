<!-- Source: p2p-comms-design.md §8 ADR-3. -->
> **Nav:** [ADR index](./README.md) · [system design](../architecture/system-design.md)

# ADR 0003: E2EE messaging protocol — X3DH + Double Ratchet at the application layer

**Status:** Proposed · **Options:** (A) rely on DTLS only; (B) Noise IK/XX per session; (C) **X3DH + Double Ratchet (chosen)**; (D) MLS for everything including 1:1.

**Trade-offs:** A has no async story (mailbox impossible), session-scoped FS only, and binds security to the transport path — fails requirement 1's spirit the moment any store-and-forward exists. B (Noise) is excellent for *online* session setup and simpler than X3DH, but has no native asynchronous prekey story or per-message PCS ratchet — we'd rebuild half of Signal around it. D is attractive as "one protocol," but MLS's Delivery-Service assumptions and machinery are heavy for 1:1, libraries are younger, and 1:1 deniability/metadata properties are better understood in Double Ratchet. **Decision: C** via libsignal or audited equivalents; MLS arrives with groups (ADR-4) rather than displacing 1:1. **Consequences:** two protocols eventually coexist (accepted; they share the identity layer); prekey lifecycle ops on the rendezvous (rotation, depletion handling) become a monitored responsibility; PQ = PQXDH slot per §4.2.

