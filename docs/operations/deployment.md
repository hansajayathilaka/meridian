# Deployment & Self-Hosting

<!-- Source: p2p-comms-design.md §9; feature spec tasks/T14 (Self-Hosting Ops Kit). -->
> **Nav:** [docs index](../INDEX.md) · [operations index](./README.md) · [deployment topology](./diagrams/deployment-topology.mermaid) · [feature 14: ops kit](../architecture/features/14-selfhosting-ops-kit.md) · [deployment skill](../../.claude/skills/deployment/SKILL.md)

See the [deployment topology diagram](./diagrams/deployment-topology.mermaid) for the air-gapped
reference deployment. The full ops-kit feature spec (with runnable install demo) is
[feature 14](../architecture/features/14-selfhosting-ops-kit.md).

## 9. Self-hosting & operations

### 9.1 What an org deploys

Two containers plus a database: `meridian-rendezvous` (single Rust binary; Postgres or embedded SQLite for prekeys/device records/mailbox/federation map), `coturn`, and TLS certs. Reference deploys: docker-compose (small org) and a Helm chart (K8s). Resource envelope: rendezvous is WebSocket fan-in + blob routing — a 2-vCPU node comfortably serves thousands of users; TURN sizing is bandwidth-bound (relayed calls ≈ 100–300 kbps audio / 1–3 Mbps video per leg) and is the only component with real capacity planning.

### 9.2 Config surface (deliberately small)

Domain + certs; federation policy (`open | allowlist | closed`) and the static federation map (air-gapped) or SRV (connected); registration admission (open, invite-token, or OIDC-gated per §3.2); mailbox TTL/quota; TURN secret + bandwidth caps; connection policy defaults (`direct|prefer-relay|relay-only`); rate-limit knobs. Everything else is client-side.

### 9.3 Air-gapped operation

Fully supported by construction: internal DNS + private CA for client-server and federation mTLS; static federation map instead of SRV; internal STUN/TURN only (clients accept an org-pushed ICE-server list, and in air-gapped mode the public-STUN default is disabled); no APNs/FCM → Android foreground-service wake, iOS foreground-only (named limitation); client updates via the org's artifact mirror with our release signatures verified offline. Nothing in the protocol phones home; there is no license server, telemetry endpoint, or key registry outside the org.

### 9.4 Observability without breaking E2EE

Exported (Prometheus): connection counts, envelope routing rates/latencies, mailbox depth/age, prekey pool levels (a real operational signal — depletion breaks first contact), federation link health, TURN allocations/bandwidth. Never exported: envelope contents (opaque by construction), contact-graph materializations, message sizes at per-user granularity (bucketed only). Logs are metadata-minimizing by default (hashed account keys with a per-deploy salt, short retention) with an org override — we document, rather than hide, that an org *can* log its own routing metadata (A1/A7 is in the threat model precisely because of this): the design's promise is that even that org reads no content and forges no identity. Client distribution is the one trust channel ops must keep out of the admins' hands alone: reproducible builds, signatures verified by the updater, and (for the web client) an audited serving origin.

---

