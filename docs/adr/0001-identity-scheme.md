<!-- Source: p2p-comms-design.md §8 ADR-1. -->
> **Nav:** [ADR index](./README.md) · [system design](../architecture/system-design.md)

# ADR 0001: Identity scheme — self-certifying key + routing hint

**Status:** Proposed · **Context:** The ID must be shareable to anyone, survive malicious servers, and work with no central directory.

| Option | Security anchor | Routability | Human factors |
|---|---|---|---|
| A. Server username (`alice@org`) | the server (fails A2) | excellent | excellent |
| B. Pure public key | the key | none — needs global lookup | poor (opaque) |
| C. **Key + `@domain` hint (chosen)** | the key | good (hint-based) | fair (QR/petnames) |
| D. Blockchain/ENS-style name→key registry | consensus system | good | good |

**Decision: C.** A gives servers key-substitution power — disqualifying under A2. B forces a DHT into v1's critical path — disqualifying for air-gapped enterprise. D imports a consensus dependency and its ops burden onto a 2–5-person team for what is, at bottom, a petname convenience; org directory attestations (§3.5) capture most of the value without it. **Consequences:** IDs are long/opaque → invest in QR + petname UX; hint staleness is a real failure mode → ID re-issue flow and (Phase 4) DHT hint-resolution fallback; server migration is user-visible but security-neutral. **Revisit** if a naming layer becomes a hard product requirement.

