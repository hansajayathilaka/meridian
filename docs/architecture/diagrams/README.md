# Architecture Diagrams

Mermaid sources. Render with any Mermaid tool (Live Editor, mermaid-cli, IDE plugin).
Sequence-diagram message text avoids `;` and `'` (Mermaid parser hazards); all sources are
syntax-validated in CI.

## Structure & components
- [System component / topology](./system-component.mermaid) — two-org deployment, control vs. data plane.
- [Core module architecture](./core-modules.mermaid) — `meridian-core` layers + `Transport`/`SecretStore` traits.
- [Key hierarchy](./key-hierarchy.mermaid) — identity → prekeys → X3DH → ratchet → stream/media/file keys.
- [Stream-type plugin architecture](./stream-plugin.mermaid) — the extension contract.
- [Build / target topology](./build-target-topology.mermaid) — one Rust core → five targets.

## State machines
- [Session state machine](./session-state-machine.mermaid)
- [Contact trust state machine](./trust-state-machine.mermaid)

## Sequences
- [Cross-org session setup](./seq-cross-org-setup.mermaid)
- [File transfer](./seq-file-transfer.mermaid)
- [Call with relay fallback](./seq-call-relay-fallback.mermaid)
- [Device provisioning](./seq-device-provisioning.mermaid)
- [Offline mailbox lifecycle](./seq-offline-mailbox.mermaid)

Deployment topology lives with operations: [../../operations/diagrams/deployment-topology.mermaid](../../operations/diagrams/deployment-topology.mermaid).
