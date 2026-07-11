<!-- Source: p2p-comms-design.md §8 ADR-5. -->
> **Nav:** [ADR index](./README.md) · [system design](../architecture/system-design.md)

# ADR 0005: Multi-device — account-signed device subkeys, per-device sessions

**Status:** Proposed · **Options:** (A) copy the identity key to every device; (B) **per-device subkeys signed by the account key, Sesame-style per-device sessions (chosen)**; (C) each device is a first-class independent identity (CoMediation/"device = contact").

**Trade-offs:** A is operationally simplest and metadata-cheapest but makes every device a total-compromise single point and makes revocation meaningless. C has the cleanest crypto story but wrecks the product invariant "one shareable ID per person" and pushes device-set management onto every contact. B keeps one ID, enables true per-device revocation, and makes server-inserted ghost devices detectable (signed, versioned device record; change alerts on verified contacts) at the cost of fan-out and device-record lifecycle. **Decision: B.** **Consequences:** device add/remove is a first-class, audited flow; fan-out cost accepted at 1:1 scale; the device record becomes another object whose *authenticity* clients verify and whose *availability* the server merely provides.

