> **Nav:** [plan index](../README.md) · [ADR 0014 media stack](../../../adr/0014-media-stack.md) · [webrtc-nat-traversal skill](../../../../.claude/skills/webrtc-nat-traversal/SKILL.md)

# Phase 3 — Real transport backend: close Features 04/05 by construction

*Replaces the simulated transport so F04/F05 acceptance is proven on a real wire. Every task here is
ADR-bound (0014 media stack / 0006 terminal transport); the fingerprint and relay-only tasks are also
**[SEC]**. Gated behind the existing empty `webrtc` feature so default CI stays pure-Rust.*

**Gate before this phase:** Phase 1 (gates), T0.5.

| Task | Scope (one line) | Tags | Depends on | Status |
|---|---|---|---|---|
| [T3.1](./T3.1-webrtc-backend-skeleton.md) | webrtc-rs backend skeleton behind the `Transport` trait | [ADR] | Phase 1, T0.5 | ☐ |
| [T3.2](./T3.2-dtls-fingerprint-binding.md) | Real DTLS fingerprint binding + teardown | [ADR][SEC] | T3.1 | ☐ |
| [T3.3](./T3.3-ice-relay-only.md) | Real ICE gather + relay-only strip; observed-candidate `session info` | [ADR][SEC] | T3.1 | ☐ |
| [T3.4](./T3.4-netns-two-lan.md) | netns two-LAN rig on the real backend (F04 acceptance) | [ADR] | T3.1, T3.3 | ☐ |
| [T3.5](./T3.5-coturn-integration.md) | coturn integration + ephemeral creds e2e + single-session | [ADR][SEC] | T3.1 | ☐ |
| [T3.6](./T3.6-netns-nat-matrix-captures.md) | netns NAT matrix + tcpdump captures in CI (F05 acceptance) | [ADR][SEC] | T3.3, T3.5 | ☐ |
| [T3.7](./T3.7-sctp-soak.md) | webrtc-rs SCTP soak test | [ADR] | T3.1 | ☐ |
| [T3.8](./T3.8-timed-acceptance.md) | Timed acceptance: ≥30 min continuity, <5 s ICE restart | [ADR] | T3.4 | ☐ |
