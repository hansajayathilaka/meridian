# Monitoring & Observability (without breaking E2EE)

<!-- Source: p2p-comms-design.md §9.4 (folded into deployment.md); DOC-02 retention. -->
> **Nav:** [docs index](../INDEX.md) · [operations index](./README.md) · [deployment](./deployment.md) · [privacy & retention](../security/anonymity-and-retention.md)

The observability rules live in [deployment.md](./deployment.md) §9.4. Summary of the hard line:

**Exported (Prometheus):** connection counts, envelope routing rates/latencies, mailbox depth/age,
**prekey-pool depth** (the non-obvious alert — depletion breaks first contact), federation link
health, TURN allocations/bandwidth.

**Never exported:** envelope contents (opaque by construction), contact-graph materializations,
per-user message sizes (bucketed only). A CI metrics-endpoint lint enforces that none of the
"never" list can appear (see [test strategy](../testing/strategy.md) §6).

Logging defaults: salted-hash identifiers, short retention — see
[privacy & retention](../security/anonymity-and-retention.md).

<!-- TODO: confirm concrete alert thresholds (prekey-pool low-water mark, mailbox depth ceiling,
     federation link-down duration) — not specified in the 38 source documents. -->
