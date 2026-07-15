> **Nav:** [plan index](../README.md) · **Milestone M1** · [canonical spec: T06](../../features/06-cross-org-federation.md) · [ADR 0002 federation](../../../adr/0002-federation-mechanism.md) · [Definition of Done](../../../../CONTRIBUTING.md)

# Feature 06 — Cross-Org Federation

**Milestone:** M1 · **Depends on:** Feature 04 (needs M0 real transport, Phase 3) · **Canonical spec:**
[T06](../../features/06-cross-org-federation.md) (source of truth — this file sequences and decomposes it,
it does not restate it).

**Goal (from spec).** A user on Org A establishes a verified E2EE P2P session with a user on Org B, servers
discovering each other via DNS-SRV *or* a static federation map (air-gap), running as one script. **The
whole feature is `[ADR]` (ADR 0002) + `[SEC]` (federation).**

**Exit demo/acceptance (spec §Working output, §Acceptance):** both discovery modes pass; `closed`-policy
org rejects inbound with a clean client error; a substituted bundle from the foreign server fails closed;
killing either rendezvous after setup does not interrupt the P2P session; envelopes pass the opacity audit
at both servers.

> Tasks below are the full breakdown. Per-task files are materialised on milestone entry (see the
> [progressive-elaboration policy](../README.md#how-this-program-is-organised)).

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F06.1 | s2s transport over mTLS (WebPKI + private-CA modes) | [ADR][SEC] | M0 | ☐ |
| F06.2 | Discovery: DNS-SRV `_meridian-fed._tcp` + static `federation_map.toml` | [ADR] | F06.1 | ☐ |
| F06.3 | Federated prekey fetch + envelope forwarding (client→own→foreign→client) | [ADR][SEC] | F06.1 | ☐ |
| F06.4 | Federation policy `open\|allowlist\|closed` + edge rate limits | [SEC] | F06.1 | ☐ |
| F06.5 | First-contact message-request gate | [SEC] | F06.3 | ☐ |
| F06.6 | `demo/two-orgs/` compose stack + `federation-protocol-v1.md` | [ADR] | F06.2, F06.3 | ☐ |
| F06.7 | Cross-org abuse + opacity tests (bundle-substitution, allowlist, oversized, stale-hint) | [SEC] | F06.4, F06.6 | ☐ |

### F06.1 — s2s transport over mTLS
- **Scope.** Server-to-server channel with mutual TLS in both WebPKI and private-CA (air-gap) modes.
- **Touches.** `apps/rendezvous/src/federation/` (new). **[ADR]** ADR 0002 (s2s over mTLS) · **[SEC]** federation edge. architect + security-reviewer.
- **Deliverables.** mTLS s2s connector; cert-verification for both trust modes; **never client→foreign server directly** (§3.3 step 2 enforced structurally).
- **Tests.** mTLS handshake unit tests (valid/expired/wrong-CA); a test that a client cannot open a direct foreign connection.
- **Verification (DoD).** 3 (s2s wire versioned), 4, 5.

### F06.2 — Discovery (DNS-SRV + static map)
- **Scope.** Resolve a peer org's federation endpoint via DNS-SRV, or a static `federation_map.toml` for air-gapped deployments.
- **Touches.** `apps/rendezvous/src/federation/discovery.rs`, config. **[ADR]** ADR 0002. architect.
- **Deliverables.** Both resolvers behind one trait; stale-hint handling returns "unreachable at hint", **never a security warning** (ADR 0001 consequence).
- **Tests.** SRV-mode and static-mode resolution; stale-hint → clean unreachable error.
- **Verification (DoD).** 5, 7.

### F06.3 — Federated prekey fetch + envelope forwarding
- **Scope.** The §7.1 relay path: client → own server → foreign server → client; bundles fetched cross-org, envelopes forwarded, both opaque.
- **Touches.** `apps/rendezvous/src/federation/`, `apps/proto` (s2s frames), `apps/signaling`. **[ADR][SEC]** wire + federation. architect + security-reviewer.
- **Deliverables.** Cross-org prekey fetch with **mandatory client-side signature verification under the requested key**; envelope forwarding that keeps blobs `Vec<u8>` (no-serde-on-blob holds cross-org).
- **Tests.** End-to-end cross-org fetch+forward; the no-serde-on-blob lint passes on the federation path.
- **Verification (DoD).** 3, 4.

### F06.4 — Federation policy + edge rate limits
- **Scope.** `open | allowlist | closed` policy; per-origin-server and per-account rate limits at the federation edge.
- **Touches.** `apps/rendezvous/src/federation/policy.rs`, config. **[SEC]** anti-abuse. security-reviewer.
- **Deliverables.** Policy enforcement; `closed` rejects inbound with a clean client-side error; edge limits distinct from local limits.
- **Tests.** allowlist rejection; `closed` inbound rejection; rate-limit enforcement at the edge.
- **Verification (DoD).** 4.

### F06.5 — First-contact message-request gate
- **Scope.** A sender's intro lands in a request queue until the recipient accepts (§3.5); no session before acceptance.
- **Touches.** `apps/rendezvous`, `apps/core` (request queue), CLI UX. **[SEC]** unsolicited-contact resistance. security-reviewer.
- **Deliverables.** Request queue; accept/decline flow; no key material or session established pre-accept.
- **Tests.** Intro queued; accept → session; decline → no session, no leakage.
- **Verification (DoD).** 4.

### F06.6 — Two-orgs demo stack + protocol doc
- **Scope.** `demo/two-orgs/` docker-compose bringing up two complete stacks (rendezvous+coturn ×2, private CA, static map) on one machine; write `federation-protocol-v1.md`.
- **Touches.** `demo/two-orgs/`, `docs/api/federation-protocol-v1.md` (new), `Justfile` (`two-orgs`). **[ADR]** wire doc. architect + devops.
- **Deliverables.** One-command two-org bring-up (no internet); versioned s2s protocol doc.
- **Tests.** `just two-orgs` brings both stacks up; the demo script runs green.
- **Verification (DoD).** 3, 7.

### F06.7 — Cross-org abuse + opacity tests
- **Scope.** The adversarial acceptance: cross-org malicious-server bundle substitution (Org B lies → Alice aborts), allowlist rejection, oversized-envelope rejection, stale-hint, and the cross-org opacity audit.
- **Touches.** `harnesses/mitm-sim` (extend), `apps/rendezvous/tests`, `harnesses/opacity-audit`. **[SEC]**. security-reviewer + test-engineer.
- **Deliverables.** Cross-org cases wired into mitm-sim and the opacity audit; 0 plaintext at both servers.
- **Tests.** All abuse cases fail closed; opacity audit passes cross-org; server-kill-after-setup keeps P2P alive.
- **Verification (DoD).** 2, 4.
