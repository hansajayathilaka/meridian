# Documentation Index

All 38 source design documents, reorganized into this `docs/` tree, deduplicated and cross-linked.
This page is the map: **original document → new location**. If content was split or extracted, the
row notes where. Relative links only; everything resolves inside the repo.

Top-level sections: [architecture](./architecture/README.md) · [adr](./adr/README.md) ·
[api](./api/README.md) · [security](./security/README.md) · [testing](./testing/README.md) ·
[operations](./operations/README.md).

## Mapping: original → new location

### Master design (1)
| Original | New location | Notes |
|----------|--------------|-------|
| `p2p-comms-design.md` | [architecture/system-design.md](./architecture/system-design.md) | §1 extracted → security/threat-model.md; §8 extracted → adr/0001–0008; §9 → operations/; §11 → architecture/roadmap.md |

### Technical specs — DOC series (5)
| Original | New location | Notes |
|----------|--------------|-------|
| `DOC-01-wire-protocol-v1` | [api/wire-protocol.md](./api/wire-protocol.md) | canonical wire format |
| `DOC-02-data-model` | [architecture/data-model.md](./architecture/data-model.md) | retention §3 also referenced by security/anonymity-and-retention.md |
| `DOC-03-threat-mitigation-matrix` | [security/threat-mitigation-matrix.md](./security/threat-mitigation-matrix.md) | |
| `DOC-04-api-contracts` | [api/core-api-contracts.md](./api/core-api-contracts.md) | |
| `DOC-05-test-and-verification-strategy` | [testing/strategy.md](./testing/strategy.md) | |

### Diagrams — D series (12) + repo diagram (1)
| Original | New location |
|----------|--------------|
| `D01-system-component-architecture` | [architecture/diagrams/system-component.mermaid](./architecture/diagrams/system-component.mermaid) |
| `D02-core-module-architecture` | [architecture/diagrams/core-modules.mermaid](./architecture/diagrams/core-modules.mermaid) |
| `D03-cross-org-session-setup` | [architecture/diagrams/seq-cross-org-setup.mermaid](./architecture/diagrams/seq-cross-org-setup.mermaid) |
| `D04-key-hierarchy` | [architecture/diagrams/key-hierarchy.mermaid](./architecture/diagrams/key-hierarchy.mermaid) |
| `D05-session-state-machine` | [architecture/diagrams/session-state-machine.mermaid](./architecture/diagrams/session-state-machine.mermaid) |
| `D06-contact-trust-state-machine` | [architecture/diagrams/trust-state-machine.mermaid](./architecture/diagrams/trust-state-machine.mermaid) |
| `D07-file-transfer-sequence` | [architecture/diagrams/seq-file-transfer.mermaid](./architecture/diagrams/seq-file-transfer.mermaid) |
| `D08-call-relay-fallback-sequence` | [architecture/diagrams/seq-call-relay-fallback.mermaid](./architecture/diagrams/seq-call-relay-fallback.mermaid) |
| `D09-device-provisioning-sequence` | [architecture/diagrams/seq-device-provisioning.mermaid](./architecture/diagrams/seq-device-provisioning.mermaid) |
| `D10-offline-mailbox-sequence` | [architecture/diagrams/seq-offline-mailbox.mermaid](./architecture/diagrams/seq-offline-mailbox.mermaid) |
| `D11-deployment-topology` | [operations/diagrams/deployment-topology.mermaid](./operations/diagrams/deployment-topology.mermaid) |
| `D12-stream-type-plugin-architecture` | [architecture/diagrams/stream-plugin.mermaid](./architecture/diagrams/stream-plugin.mermaid) |
| `REPO-02-build-target-topology` | [architecture/diagrams/build-target-topology.mermaid](./architecture/diagrams/build-target-topology.mermaid) |

### Repo / stack (1 of 2; the other is the diagram above)
| Original | New location |
|----------|--------------|
| `REPO-01-languages-and-frameworks` | [architecture/stack.md](./architecture/stack.md) — ADRs §6 extracted → [adr/0009–0013](./adr/README.md) |

### Index documents — folded in (2)
| Original | Folded into |
|----------|-------------|
| `D00-DOCS-INDEX` | this file + [architecture/diagrams/README.md](./architecture/diagrams/README.md) |
| `T00-INDEX` (task index) | [architecture/roadmap.md](./architecture/roadmap.md) |

### Feature specs — T series (16)
| Original | New location |
|----------|--------------|
| `T01-identity-keystore-core` | [architecture/features/01-identity-keystore-core.md](./architecture/features/01-identity-keystore-core.md) |
| `T02-rendezvous-mvp` | [architecture/features/02-rendezvous-mvp.md](./architecture/features/02-rendezvous-mvp.md) |
| `T03-e2ee-messaging-relayed` | [architecture/features/03-e2ee-messaging-relayed.md](./architecture/features/03-e2ee-messaging-relayed.md) |
| `T04-p2p-session-substrate` | [architecture/features/04-p2p-session-substrate.md](./architecture/features/04-p2p-session-substrate.md) |
| `T05-nat-traversal-relay-policy` | [architecture/features/05-nat-traversal-relay-policy.md](./architecture/features/05-nat-traversal-relay-policy.md) |
| `T06-cross-org-federation` | [architecture/features/06-cross-org-federation.md](./architecture/features/06-cross-org-federation.md) |
| `T07-offline-mailbox` | [architecture/features/07-offline-mailbox.md](./architecture/features/07-offline-mailbox.md) |
| `T08-verification-trust` | [architecture/features/08-verification-trust.md](./architecture/features/08-verification-trust.md) |
| `T09-file-transfer` | [architecture/features/09-file-transfer.md](./architecture/features/09-file-transfer.md) |
| `T10-av-calls-screenshare` | [architecture/features/10-av-calls-screenshare.md](./architecture/features/10-av-calls-screenshare.md) |
| `T11-browser-desktop-clients` | [architecture/features/11-browser-desktop-clients.md](./architecture/features/11-browser-desktop-clients.md) |
| `T12-mobile-clients` | [architecture/features/12-mobile-clients.md](./architecture/features/12-mobile-clients.md) |
| `T13-multi-device` | [architecture/features/13-multi-device.md](./architecture/features/13-multi-device.md) |
| `T14-selfhosting-ops-kit` | [architecture/features/14-selfhosting-ops-kit.md](./architecture/features/14-selfhosting-ops-kit.md) |
| `T15-location-stickers` | [architecture/features/15-location-stickers.md](./architecture/features/15-location-stickers.md) |
| `T16-tier2-tunnels` | [architecture/features/16-tier2-tunnels.md](./architecture/features/16-tier2-tunnels.md) |

**Count:** 1 master + 5 DOC + 13 diagrams + 1 stack + 2 indexes + 16 features = **38**. ✔

## Gaps & contradictions found (during reorganization)

1. **The prompt's "Tech stack" bullet was empty.** Stack taken as canonical from
   [architecture/stack.md](./architecture/stack.md) (`REPO-01`). Flagged, not invented.
2. **"Anonymity" is scoped down deliberately.** The design does not claim Tor-grade anonymity; it
   provides pseudonymous key-identity + E2EE + optional relay-only IP-hiding with org-bounded
   metadata. The [privacy model](./security/anonymity-and-retention.md) states this honestly and the
   [anonymity-model skill](../.claude/skills/anonymity-model/SKILL.md) enforces the honest scope.
3. **"No application server" vs. the ciphertext mailbox** — an intentional, disclosed tension, fully
   reconciled in [ADR 0007](./adr/0007-offline-mailbox.md). Not a defect.
4. **Two open decisions remain open:** [ADR 0011](./adr/0011-ratchet-library.md) (ratchet library)
   and libwebrtc-vs-pure-Rust media ([ADR 0006](./adr/0006-terminal-transport.md) / design §12).
5. **Operational specifics absent** (alert thresholds, on-call, backup cadence) are marked
   `<!-- TODO: confirm -->` in [operations/monitoring.md](./operations/monitoring.md) and
   [operations/runbook.md](./operations/runbook.md) rather than invented.

## Additions at handoff (not part of the original 38)

These were created to make the scaffold Claude-Code-ready; see
[handoff-readiness.md](./handoff-readiness.md) for the full decisions log.

| New document | Purpose |
|--------------|---------|
| [handoff-readiness.md](./handoff-readiness.md) | Every pre-handoff decision, with pros/cons and where it landed |
| [adr/0014-media-stack.md](./adr/0014-media-stack.md) | Resolves the open media-stack question (libwebrtc + webrtc-rs) |
| [security/verification-ux.md](./security/verification-ux.md) | Canonical, un-softenable key-change / safety-number warning wording |
| [glossary.md](./glossary.md) | Shared vocabulary |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Workflow + global Definition of Done |

[ADR 0011](./adr/0011-ratchet-library.md) was moved from *open* to **Accepted** (vodozemac).
New Claude Code tooling: skills `crypto-protocols`, `webrtc-nat-traversal`, `stream-type-authoring`;
agent `connectivity-debugger`; commands `/adr`, `/spike`. Runnable skeleton: `meridian-proto` crate,
`tools/xtask`, three enforcement lints under `tools/`, harness stubs under `harnesses/`, and
`test-vectors/`.
